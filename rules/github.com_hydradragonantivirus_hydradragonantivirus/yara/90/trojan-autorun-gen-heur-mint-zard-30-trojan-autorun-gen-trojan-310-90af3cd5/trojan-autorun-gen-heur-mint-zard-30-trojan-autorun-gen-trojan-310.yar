rule _Trojan_Autorun_Gen_Heur_Mint_Zard_30_Trojan_Autorun_Gen_Trojan__310 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Heur.Mint.Zard.30.vir, Trojan.Autorun_Gen.Trojan.ShellReg.UGZ@aW4SuOnb.vir, Trojan.Autorun_Generic.Dacic.E1F05845.A.489D47DA.vir, Trojan.Autorun_Generic.Dacic.E1F05845.A.489D47DA_1.vir, Trojan.Autorun_Trojan.GenericKDZ.74315.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@ayJVeyi_19.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_22_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_23_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_24_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_25_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_27_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_28_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ae15743bb72e2e70ed459819a6f5033d3221fecc5ca0c7ade59c9b567ca70f0"
    hash2       = "579bb17e23f52d3800c9ac5f62413b600c305191529d8436b7c05fd44296c05e"
    hash3       = "b3a740f92d926d52b649bfc452637b1495bbd25b5e8e887318db1e3111b4b10d"
    hash4       = "d435243e0254f90079db2bfdb75c15b3d56adb65f9bdc6a4e45486e8e193148b"
    hash5       = "8bc1e5b673a3530f7d6a960763cdb82bcf5d937c5576f399d92b7ed4ec437334"
    hash6       = "ea2f4f8e76ddc88d6f7515777738a4d55a82e21f5f94ec3e6d109063f288a77d"
    hash7       = "f6c19c5b54c39c80d017b5562d76c7e6733dc11656f2ff41f48fbf8b4d67d930"
    hash8       = "a5559e16e109990948771fb9eb986214947ee060b567cb10518dd93f86d7964d"
    hash9       = "11a025d669d7755e52c32d767ffa705a655d9373a46e6c94498a7651b4dc60be"
    hash10      = "980582154d9d723f27b5748e7bc8c8567e2dd2e89cbf46da996dd4d1ea05ac67"
    hash11      = "57b31f7187348350c2c436614c645f64e6a2a732a7b9a6c5683f74daf6cf8d0b"
    hash12      = "418a39121a36c1b18487934b3d43719d3daa1ccf5283270c4580c9c1a195aa2c"
    hash13      = "aff030b8607056c296344a8ba6b2b637c6b7b803ebfee940df002f178a3dec79"
    hash14      = "b3186a8688e22b720472f3951f9e75c45a8fae24efa1af90063b2353a66975c8"
    hash15      = "2afbf378b54b844ef8c6ccb55715c9d8ead46b1ab672c01c16517dc272cd6ea6"

  strings:
    $s1  = "Host Lookup Failed" fullword ascii
    $s2  = "Incomplete Header" fullword ascii
    $s3  = "Host Lookup Timed Out" fullword ascii
    $s4  = "Error creating Data Connection" fullword ascii
    $s5  = "Checking Connection" fullword ascii
    $s6  = "Resolve Host" fullword ascii
    $s7  = "High Version= " fullword ascii
    $s8  = "Socket readln aborted" fullword ascii
    $s9  = "Connection Timed out" fullword ascii
    $s10 = "Timer Triggered" fullword ascii
    $s11 = "Invalid seek origin = %d" fullword ascii
    $s12 = "Clearing Input" fullword ascii
    $s13 = "Timer On" fullword ascii
    $s14 = "Max Udp pack size= " fullword ascii
    $s15 = "Request Close Socket" fullword ascii
    $s16 = "Data Available" fullword ascii
    $s17 = "Timer Off" fullword ascii
    $s18 = "PutBack overflow" fullword ascii
    $s19 = "Sending Buffer" fullword ascii
    $s20 = "Socket send aborted" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}