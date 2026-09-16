rule _Virus_Autorun_Gen_Heur_Mint_Autorunner_1_Virus_Autorun_Gen_Vari_413 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Heur.Mint.Autorunner.1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_15_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_14_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_233_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aefdc6da05cfd4012097251989683d30f21626362c29463da121dc621046b2b6"
    hash2       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash3       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash4       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash5       = "940de455f281b3225827ecddd883f1b43ba1368dbd7f57716d0a339045f24379"
    hash6       = "b9b6d8d4e5e6cd4b77e5a6c7210788216aa3bb117891716f5015552052351ce2"
    hash7       = "a5dfab92bc0fe88046376c003f550774217c4668c8d766ded7b45a5d3fd4eab0"
    hash8       = "4f08e3a69121dfc3731f51c33e40cb14ff28c745c3471bd8ec1328cb7426f648"
    hash9       = "30f2f4066055982aa217e1da873c8c5306b812730a14c821c3dca50fec8f4fef"

  strings:
    $s1  = "BuildAPurbleGame::FormatScore() - Unable to get the negative number style" fullword wide
    $s2  = "CardTable::PopState() - Failed to create a new stack." fullword wide
    $s3  = "CardTable::SplitStack() - Failed to create a new stack." fullword wide
    $s4  = "Couldn't find cards for targeted hint animation" fullword wide
    $s5  = "CardTable::PopState() - Couldn't find the card to lock/unlock." fullword wide
    $s6  = "CardTable::PopState() - Couldn't find the card to flip." fullword wide
    $s7  = "CardTable::PopState() - Couldn't find the stack to pop." fullword wide
    $s8  = "CardTable::PopState() - Couldn't find the card to push." fullword wide
    $s9  = "CardTable::PopState() - Couldn't find the stack to push to." fullword wide
    $s10 = "CardTable::PopState() - Couldn't find the stack to reverse." fullword wide
    $s11 = "CardTable::PopState() - Couldn't find the stack to destroy." fullword wide
    $s12 = "CardStack::ArrangeHint() - Got a null card from the card array." fullword wide
    $s13 = "Unable to write the version to the GameState node" fullword wide
    $s14 = "Failed to create a new container" fullword wide
    $s15 = "Failed to create tip container" fullword wide
    $s16 = "Unable to create the GameState node." fullword wide
    $s17 = "Stack%d" fullword wide
    $s18 = "Missing a main stack in the layout" fullword wide
    $s19 = "Stack is missing a name" fullword wide
    $s20 = "Card is missing a name" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}