import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_14_1_Troj_269 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_14_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_196_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_274_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_318_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_357_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_386_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_404_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_481_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.syZ@a0MYK1d.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39434c31466549f8571eeb219c3bea431b78ab9fbad49ac2f7fcd3acb151161b"
    hash2       = "5db92100a444603af6ed9abe3cf6b8e3985e68465f698da33c3d8444049d6a83"
    hash3       = "110d3f3fddc5e916ea27ef3443875ad675fcadd31daa4c5a8f5e3897aee7a91e"
    hash4       = "b63c22fdd4e5500ed75679851d36235e63255eb02f400558439e5ffe432d203e"
    hash5       = "b711ef49663b0baff285a4fb481eac2a627c01986fb5916cd673956fbb25a922"
    hash6       = "a223e99d430c9a413e04c7aa83e09a282cfe00ad34e7accd4a266e8577d09afe"
    hash7       = "d3769d9adff28809979d40939dbf77d05fef9aed65c6edf66fcc3f4a9e87e912"
    hash8       = "e4ecc894068722495d89387d1444e7c9c03ed0e047035cb27efaa1f2e2516a85"
    hash9       = "3d810e8cd10b618cf3c5582c783986b77a3602679b9abdc64adf5ad7986ad020"

  strings:
    $s1 = "), 'trained': False, 'input_shape': (1, 1048576), 'softmax_outputs': False, 'batch_size': 256, 'loss': 'binary_crossentropy', 'o" ascii
    $s2 = "nges_per_iterations_': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec" ascii
    $s3 = "3d00>, 'is_debug': False, 'minimization_result_': array([3.28546224e-01, 2.07056797e-01, 8.06170856e-01, 6.47791155e-02," fullword ascii
    $s4 = ".2339580926513674, 3.2339580926513674, 3.2339580926513674, 3.2339580926513674, 3.2339580926513674, 3.2339580926513674, 3.2339580" ascii
    $s5 = "_phi.CEnd2EndWrapperPhi object at 0x7f5cA" fullword ascii
    $s6 = "?0823, 380823, 380823, 380823, 377512, 354741, 354741, 354741, 354741, 354741, 354741, 354741, 354741, 354741, 354741, 354741, 3" ascii
    $s7 = "apper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5cA" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c2a87fabf96470db507b2e6b43bd92eb" and (all of them)
    ) or (all of them)
}