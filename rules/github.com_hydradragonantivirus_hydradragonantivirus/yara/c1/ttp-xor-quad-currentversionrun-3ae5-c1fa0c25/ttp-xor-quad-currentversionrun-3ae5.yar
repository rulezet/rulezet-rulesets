rule TTP_XOR_QUAD_CurrentVersionRun_3ae5 {
  strings:
    $key_3ae5 = { 69 8a [2] 4d 84 [2] 66 a8 [2] 48 8a [2] 5c 91 [2] 53 8b [2] 4d 96 [2] 4f 97 [2] 54 91 [2] 48 96 [2] 54 b9 }

  condition:
    any of them
}