import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_9_1_Virus_Hijac_230 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.mvZ@amBwvTb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8178aa730e044365fcc4665f1bc4ffcf682d25cbb4e268cbdfd1e02a59e3a7b"
    hash2       = "6f2ea01918463d6c86c8675a48274811e2b0e3d6c4eff1cdddf8c0db301e8f4a"

  strings:
    $s1  = ".?AV?$thread_data@V?$bind_t@XP6AXV?$shared_ptr@Ushared_state_base@detail@boost@@@boost@@@ZV?$list1@V?$value@V?$shared_ptr@U?$fut" ascii
    $s2  = ".?AV?$thread_data@V?$bind_t@XP6AXV?$shared_ptr@Ushared_state_base@detail@boost@@@boost@@@ZV?$list1@V?$value@V?$shared_ptr@U?$fut" ascii
    $s3  = ".?AV?$thread_data@V?$bind_t@XP6AXV?$shared_ptr@Ushared_state_base@detail@boost@@@boost@@@ZV?$list1@V?$value@V?$shared_ptr@U?$fut" ascii
    $s4  = "result@autobahn@@@2@@Z@U?$future_async_shared_state_base@X@detail@2@@detail@boost@@" fullword ascii
    $s5  = ".?AU?$future_deferred_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?1???R3?CM@??table_release@@YAXXZ@QBE@V12@@Z@@de" ascii
    $s6  = ".?AU?$future_async_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?1???R3?CM@??table_release@@YAXXZ@QBE@V12@@Z@@detai" ascii
    $s7  = ".?AU?$continuation_shared_state@V?$future@_K@boost@@XV<lambda_1>@?1???R3?1???R3?CM@??table_release@@YAXXZ@QBE@V?$future@X@2@@Z@Q" ascii
    $s8  = ".?AU?$future_deferred_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?1???R3?1???R3?1???R3?1???R3?1???R3?CM@??table_r" ascii
    $s9  = ".?AU?$future_deferred_continuation_shared_state@V?$future@_K@boost@@XV<lambda_1>@?1???R3?1???R3?CM@??table_release@@YAXXZ@QBE@V?" ascii
    $s10 = ".?AV?$sp_counted_impl_p@U?$future_deferred_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?1???R3?CM@??table_release@" ascii
    $s11 = "ure_async_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?1???R3?1???R3?1???R3?1???R3?1???R3?CM@??table_release@@YAXX" ascii
    $s12 = ".?AV?$sp_counted_impl_p@U?$future_deferred_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?CM@??table_release@@YAXXZ@" ascii
    $s13 = ".?AU?$continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?CM@??table_release@@YAXXZ@U?$future_async_shared_state_base@X@d" ascii
    $s14 = ".?AU?$future_async_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?CM@??table_release@@YAXXZ@@detail@boost@@" fullword ascii
    $s15 = ".?AV?$sp_counted_impl_p@U?$future_deferred_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?CM@??table_release@@YAXXZ@" ascii
    $s16 = ".?AU?$future_deferred_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?1???R3?CM@??table_release@@YAXXZ@QBE@V12@@Z@@de" ascii
    $s17 = ".?AU?$future_async_continuation_shared_state@V?$future@_K@boost@@XV<lambda_1>@?1???R3?1???R3?CM@??table_release@@YAXXZ@QBE@V?$fu" ascii
    $s18 = ".?AU?$continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?1???R3?CM@??table_release@@YAXXZ@QBE@V12@@Z@U?$shared_state@X@d" ascii
    $s19 = ".?AU?$future_sync_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?CM@??table_release@@YAXXZ@@detail@boost@@" fullword ascii
    $s20 = ".?AV?$sp_counted_impl_p@U?$future_async_continuation_shared_state@V?$future@X@boost@@XV<lambda_1>@?1???R3?CM@??table_release@@YA" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "47d186778bc9d198554e460e0d3becb7" and (8 of them)
    ) or (all of them)
}