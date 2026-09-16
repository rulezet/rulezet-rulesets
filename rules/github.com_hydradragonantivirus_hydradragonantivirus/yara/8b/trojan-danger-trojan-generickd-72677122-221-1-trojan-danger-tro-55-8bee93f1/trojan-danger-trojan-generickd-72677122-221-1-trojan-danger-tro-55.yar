import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72677122_221_1_Trojan_Danger_Tro_55 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_221_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_222_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_223_1.vir, Trojan.Danger_Trojan.GenericKD.72677122_224_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7ed16377c782efc1c40dd33935a3e404494185449ed018ef14b85f71ee56224"
    hash2       = "16ae326ffa317838a9db93df09c274e95a8abf2133d22b613d360b74cc10b3da"
    hash3       = "6944b35ad0b4a910dc0fc6fd91654d64d974d4f597381f056a36b5278f60698b"
    hash4       = "dec24a6e003f647568c9197f3ce2cd4510befb518fb783f309ae00ee6bcc9aca"

  strings:
    $s1  = "s audit andgqmtyu*x*x*x#$#$21l5199414crdkosq*x*x*x#$#$21f5199416esfykyd*x*x*x#$#$21q5199417gkibbjn*x*x*x#$#$21r5199418hwwaegb*x*" ascii
    $s2  = "Processor basis may be accessed by your internal users (including agents and contractors) and by third party users. For the*x*x*" ascii
    $s3  = "not bypass or circumvent" fullword ascii
    $s4  = "#$11b5192357jrmjenw*x*x*x#$#$14o519145654hiuhgcn*x*x*x#$#$16x519204320hpdoadu*x*x*x#$#$16w519204322goakydo*x*x*x#$#$16n519204323" ascii
    $s5  = "update this feature. For more information, go to9204422fjkmlke*x*x*x#$#$16u519204424fdlxuok*x*x*x#$#$16w519204425sloykkb*x*x*x#$" ascii
    $s6  = "#$16i519204426gestnxf*For new or unsupported customers, please contact your Oracle Account Manager for this information." fullword ascii
    $s7  = "you become subject to insolvency or other similar legal proceedings, you will promptly send written notice to: Oracle EMEA199311" ascii
    $s8  = "the date your order is accepted by Oracle, and you must acquire products and must use any acquired services prior to the end2046" ascii
    $s9  = "you become subject to insolvency or other similar legal proceedings, you will promptly send written notice to: Oracle EMEA199311" ascii
    $s10 = "the date your order is accepted by Oracle, and you must acquire products and must use any acquired services prior to the end2046" ascii
    $s11 = "may contact the manufacturer or installer to determine its return policy and" fullword ascii
    $s12 = "19204322goakydo*x*x*x#$#$16n519204323swpnknq*x*x*x#$#$16w519204324lejtgmh*x*x*x#$#$16j519204325weslgyq*xFEA TURES. Instead, you " ascii
    $s13 = "terms on those websites.#$21x519946ihnwqqdp*x*x*x#$#$21t519947ixslovdm*x*x*x#$#$21f519948xeglpqsc*x*x*x#$#$21p519949qakgllyh*x*x" ascii
    $s14 = "120103_Def_V122304 Page 7 of 11 " fullword ascii
    $s15 = "19204322goakydo*x*x*x#$#$16n519204323swpnknq*x*x*x#$#$16w519204324lejtgmh*x*x*x#$#$16j519204325weslgyq*xFEA TURES. Instead, you " ascii
    $s16 = "terms on those websites.#$21x519946ihnwqqdp*x*x*x#$#$21t519947ixslovdm*x*x*x#$#$21f519948xeglpqsc*x*x*x#$#$21p519949qakgllyh*x*x" ascii
    $s17 = "#$#$21t5199323bocnefe*x*x*x#$#$21i5199324tqfikhm*x*software, which is licensed " fullword ascii
    $s18 = "trial software are limited to the trial period. The trial software and length of the trial period" fullword ascii
    $s19 = "update this feature. For more information, go to9204422fjkmlke*x*x*x#$#$16u519204424fdlxuok*x*x*x#$#$16w519204425sloykkb*x*x*x#$" ascii
    $s20 = "confidential legends or markings placed upon the TRMs. Oracle shall retain all title, copyright and other proprietary rights ixD" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "13d2400720cd245b44b45a162241616d" and (8 of them)
    ) or (all of them)
}