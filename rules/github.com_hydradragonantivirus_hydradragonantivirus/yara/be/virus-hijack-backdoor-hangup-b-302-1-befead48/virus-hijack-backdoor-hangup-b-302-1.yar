rule Virus_Hijack_Backdoor_Hangup_B_302_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_302_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd2edca35aabb6235400fc11c85404b7ae246e3bde4eff98b75b0742089402b5"

  strings:
    $s1 = "attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, 'minimization_result_': array([0." ascii
    $s2 = "3937921524, 0.1284043937921524, 0.1284043937921524, 0.1284043937921524, 0.1284043937921524, 0.1284043937921524, 0.12840439379215" ascii
    $s3 = "erations_': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_" ascii
    $s4 = "24, 0.1284043937921524, 0.1284043937921524, 0.1284043937921524, 0.1284043937921524, 0.1284043937921524, 0.1284043937921524, 0.12" ascii
    $s5 = "debug': False, 'minimization_result_': array([0.20277018, 0.32673794, 0.32629699, 0.80278205, 0.00705552," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}