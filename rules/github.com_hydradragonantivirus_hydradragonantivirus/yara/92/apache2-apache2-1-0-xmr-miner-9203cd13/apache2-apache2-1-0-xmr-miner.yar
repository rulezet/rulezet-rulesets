rule _apache2_apache2_1_0_XMR_MINER {
  meta:
    description = "case125 - from files apache2, apache2-1"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-08"
    hash1       = "3d18f4f503a72a4246b1a13327745fab15f9b34f45e17d4f6e94a311427ad4da"
    hash2       = "b04dcace214ddb4f88efeb1a495bc123739abe8eb9815991f421e6466f893656"

  strings:
    $x1  = "{\"method\":\"login\",\"params\":{\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"xmr-stak-cpu/1.3.0-1.5.0\"},\"id\":1}" fullword ascii
    $s2  = "Autoconf failed: Printing config for a single thread. Please try to add new ones until the hashrate slows down." fullword ascii
    $s3  = "_ZSt25notify_all_at_thread_exitRSt18condition_variableSt11unique_lockISt5mutexE" fullword ascii
    $s4  = "CONNECT error: Pool port number not specified, please use format <hostname>:<port>." fullword ascii
    $s5  = "The values are not optimal, please try to tweak the values based on notes in config.txt." fullword ascii
    $s6  = "Pool connection lost. Waiting %lld s before retry (attempt %llu)." fullword ascii
    $s7  = "PARSE error: Login protocol error 1" fullword ascii
    $s8  = "PARSE error: Login protocol error 3" fullword ascii
    $s9  = "PARSE error: Login protocol error 2" fullword ascii
    $s10 = "_ZNSt18condition_variable4waitERSt11unique_lockISt5mutexE" fullword ascii
    $s11 = "_ZGTtNSt11logic_errorC2ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
    $s12 = "_ZGTtNSt11logic_errorC1ERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE" fullword ascii
    $s13 = "_ZTISt11_Mutex_baseILN9__gnu_cxx12_Lock_policyE2EE" fullword ascii
    $s14 = "_ZTSSt11_Mutex_baseILN9__gnu_cxx12_Lock_policyE2EE" fullword ascii
    $s15 = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPcEEvT_S7_St20forward_iterator_tag" fullword ascii
    $s16 = "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE12_M_constructIPKcEEvT_S8_St20forward_iterator_tag" fullword ascii
    $s17 = "_Z26_txnal_logic_error_get_msgPv" fullword ascii
    $s18 = "execute_native_thread_routine_compat" fullword ascii
    $s19 = "_ZNSs12_S_constructIN9__gnu_cxx17__normal_iteratorIPcSsEEEES2_T_S4_RKSaIcESt20forward_iterator_tag" fullword ascii
    $s20 = "Autoconf failed: L3 size sanity check failed - %u KB." fullword ascii

  condition:
    (uint16(0) == 0x457f and
      filesize < 5000KB and (1 of ($x*) and 4 of them)
    ) or (all of them)
}