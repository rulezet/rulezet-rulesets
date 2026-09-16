rule TTP_XOR_QUAD_CurrentVersionRun_dee4 {
  strings:
    $key_dee4 = { 8d 8b [2] a9 85 [2] 82 a9 [2] ac 8b [2] b8 90 [2] b7 8a [2] a9 97 [2] ab 96 [2] b0 90 [2] ac 97 [2] b0 b8 }

  condition:
    any of them
}