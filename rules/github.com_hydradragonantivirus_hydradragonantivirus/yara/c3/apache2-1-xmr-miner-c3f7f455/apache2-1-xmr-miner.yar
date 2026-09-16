rule apache2_1_XMR_MINER {
  meta:
    description = "case125 - file apache2-1"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "b04dcace214ddb4f88efeb1a495bc123739abe8eb9815991f421e6466f893656"

  strings:
    $x1  = "{\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"xmr-stak-cpu/1.3.0-1.5.0\"},\"id\":1}" fullword ascii
    $s2  = "_ZNSt6vectorIN8executor13sck_error_logESaIS1_EE19_M_emplace_back_auxIJSsEEEvDpOT_" fullword ascii
    $s3  = "Autoconf failed: Printing config for a single thread. Please try to add new ones until the hashrate slows down." fullword ascii
    $s4  = "_ZNKSt7__cxx118time_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE3getES4_S4_RSt8ios_baseRSt12_Ios_IostateP2tmPKwSD_" fullword ascii
    $s5  = "_ZNKSt7__cxx118time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE3getES4_S4_RSt8ios_baseRSt12_Ios_IostateP2tmPKcSD_" fullword ascii
    $s6  = "_ZSt25notify_all_at_thread_exitRSt18condition_variableSt11unique_lockISt5mutexE" fullword ascii
    $s7  = "_ZNKSt8time_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE3getES3_S3_RSt8ios_baseRSt12_Ios_IostateP2tmPKwSC_" fullword ascii
    $s8  = "_ZNKSt8time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE3getES3_S3_RSt8ios_baseRSt12_Ios_IostateP2tmPKcSC_" fullword ascii
    $s9  = "_ZTINSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEEE" fullword ascii
    $s10 = "_ZTSNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEEE" fullword ascii
    $s11 = "_ZNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEED0Ev" fullword ascii
    $s12 = "_ZNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEED1Ev" fullword ascii
    $s13 = "_ZTVNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEEE" fullword ascii
    $s14 = "_ZNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEED2Ev" fullword ascii
    $s15 = "_ZNSt6thread11_State_implISt12_Bind_simpleIFSt7_Mem_fnIM8executorFvvEEPS3_EEE6_M_runEv" fullword ascii
    $s16 = "CONNECT error: Pool port number not specified, please use format <hostname>:<port>." fullword ascii
    $s17 = "The values are not optimal, please try to tweak the values based on notes in config.txt." fullword ascii
    $s18 = "_ZN8executor16log_result_errorEOSs" fullword ascii
    $s19 = "_ZNKSt9money_getIwSt19istreambuf_iteratorIwSt11char_traitsIwEEE6do_getES3_S3_bRSt8ios_baseRSt12_Ios_IostateRSbIwS2_SaIwEE" fullword ascii
    $s20 = "_ZNKSt7__cxx118time_getIcSt19istreambuf_iteratorIcSt11char_traitsIcEEE11get_weekdayES4_S4_RSt8ios_baseRSt12_Ios_IostateP2tm" fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 5000KB and
      (1 of ($x*) and 4 of them)
    ) or (all of them)
}