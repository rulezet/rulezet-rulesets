rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efd3b3fd61b5aaaa20e2aa41067dda9f38899fbda40ed9521e23554b78b55fea"

  strings:
    $s1  = "    name   = 'Microsoft.Windows.Common-Controls' version  = '6.0.0.0' processorArchitecture =   '*'" fullword ascii
    $s2  = ".?AV?$service_base@V?$resolver_service@Vudp@ip@asio@boost@@@detail@asio@boost@@@detail@asio@boost@@" fullword ascii
    $s3  = ".?AV?$service_base@V?$win_iocp_socket_service@Vudp@ip@asio@boost@@@detail@asio@boost@@@detail@asio@boost@@" fullword ascii
    $s4  = ".?AV?$_Associated_state@V?$basic_resolver_results@Vudp@ip@asio@boost@@@ip@asio@boost@@@std@@" fullword ascii
    $s5  = ".?AU?$_Deleter_base@V?$basic_resolver_results@Vudp@ip@asio@boost@@@ip@asio@boost@@@std@@" fullword ascii
    $s6  = ".?AU?$_State_deleter@V?$basic_resolver_results@Vudp@ip@asio@boost@@@ip@asio@boost@@V?$_Associated_state@V?$basic_resolver_result" ascii
    $s7  = ".?AU?$_State_deleter@IV?$_Associated_state@I@std@@V?$allocator@D@2@@std@@" fullword ascii
    $s8  = ".?AU?$_State_deleter@V?$basic_resolver_results@Vudp@ip@asio@boost@@@ip@asio@boost@@V?$_Associated_state@V?$basic_resolver_result" ascii
    $s9  = ".?AV?$_Ref_count_obj_alloc@V?$promise@V?$basic_resolver_results@Vudp@ip@asio@boost@@@ip@asio@boost@@@std@@V?$allocator@D@2@@std@" ascii
    $s10 = "s@Vudp@ip@asio@boost@@@ip@asio@boost@@@std@@V?$allocator@D@6@@std@@" fullword ascii
    $s11 = ".?AV?$_Ref_count_obj_alloc@V?$promise@I@std@@V?$allocator@D@2@@std@@" fullword ascii
    $s12 = ".?AV?$_Ref_count_obj_alloc@V?$promise@V?$basic_resolver_results@Vudp@ip@asio@boost@@@ip@asio@boost@@@std@@V?$allocator@D@2@@std@" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}