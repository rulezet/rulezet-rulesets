rule TTP_XOR_QUAD_CurrentVersionRun_dbe4 {
  strings:
    $key_dbe4 = { 88 8b [2] ac 85 [2] 87 a9 [2] a9 8b [2] bd 90 [2] b2 8a [2] ac 97 [2] ae 96 [2] b5 90 [2] a9 97 [2] b5 b8 }

  condition:
    any of them
}