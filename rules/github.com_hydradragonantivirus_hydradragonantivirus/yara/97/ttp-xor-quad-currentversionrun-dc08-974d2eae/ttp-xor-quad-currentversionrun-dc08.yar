rule TTP_XOR_QUAD_CurrentVersionRun_dc08 {
  strings:
    $key_dc08 = { 8f 67 [2] ab 69 [2] 80 45 [2] ae 67 [2] ba 7c [2] b5 66 [2] ab 7b [2] a9 7a [2] b2 7c [2] ae 7b [2] b2 54 }

  condition:
    any of them
}