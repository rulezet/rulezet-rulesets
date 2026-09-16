rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_16_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_16_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35b99b44e8bff0ba86d4748a5b5c6e96836858e789eea8bb30439bc377fdaf67"

  strings:
    $s1  = "command sounded, and were repeated in the rear, where ponies and men lay hidden. The guns were run back under cover, and with li" ascii
    $s2  = "The order was given to march, and, headed by the pipers, who com" fullword ascii
    $s3  = " place, some of the reserves were not under cover, and the battery commander so exposed himself that hed have been a dead man be" ascii
    $s4  = "the constant roar, watched the bursting shells with interest." fullword ascii
    $s5  = "Time after time the range was increased, until, at last, the shells were dropped just a" fullword ascii
    $s6  = "d time to fire they would have been shelled out of their position." fullword ascii
    $s7  = " place, some of the reserves were not under cover, and the battery commander so exposed himself that hed have been a dead man be" ascii
    $s8  = "en next instant the first gun boomed forth, and a shell went screaming through the air towards the low range of sand-hi" fullword ascii
    $s9  = "f a dull, drab house in the Vauxhall Bridge Road, close to Victoria Station in London, the narrow-eyed man who had so closely qu" ascii
    $s10 = "She turned towards him, separate, remote, incongruous, her dark eyes showing an angry flash in them." fullword ascii
    $s11 = "head, while the flash could be seen long before the report reached the ear." fullword ascii
    $s12 = "y whether Fetherston, whom he minutely described, had been there that day. At first the head waiter hesitated and was uncommunic" ascii
    $s13 = "nd approached the position by a circ" fullword ascii
    $s14 = "command sounded, and were repeated in the rear, where ponies and men lay hidden. The guns were run back under cover, and with li" ascii
    $s15 = "ddle and watching it all through his monocle with critical eye, and keeping up a fire of sarcastic comment directed at the colon" ascii
    $s16 = "menced their inspiring skirl to the beat of the drums, they moved away over the rough, broken ground, the general standing astra" ascii
    $s17 = "the pipers were lying concealed in a depression close at hand when they arrived." fullword ascii
    $s18 = "Walter Fetherston held his breath. His lips were pressed tightly together, his brows contracted. He was again to meet Enid Orleb" ascii
    $s19 = "She held her breath, staring straight into his eyes." fullword ascii
    $s20 = "Enid, he answered in a low voice, with honesty in his eyes, I would rather sacrifice my great love for you than betray the trust" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}