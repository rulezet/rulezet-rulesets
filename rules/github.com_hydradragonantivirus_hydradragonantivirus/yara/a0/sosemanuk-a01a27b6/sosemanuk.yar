rule Sosemanuk {
  

  strings:
    $mul_a_be  = { 00 00 00 00 E1 9F CF 13 6B 97 37 26 8A 08 F8 35 [992] B5 5B 4D DE 54 C4 82 CD DE CC 7A F8 3F 53 B5 EB }
    $mul_a_le  = { 00 00 00 00 13 CF 9F E1 26 37 97 6B 35 F8 08 8A [992] DE 4D 5B B5 CD 82 C4 54 F8 7A CC DE EB B5 53 3F }
    $mul_ia_be = { 00 00 00 00 18 0F 40 CD 30 1E 80 33 28 11 C0 FE [992] 9E E2 65 1C 86 ED 25 D1 AE FC E5 2F B6 F3 A5 E2 }
    $mul_ia_le = { 00 00 00 00 CD 40 0F 18 33 80 1E 30 FE C0 11 28 [992] 1C 65 E2 9E D1 25 ED 86 2F E5 FC AE E2 A5 F3 B6 }

  condition:
    any of them
}