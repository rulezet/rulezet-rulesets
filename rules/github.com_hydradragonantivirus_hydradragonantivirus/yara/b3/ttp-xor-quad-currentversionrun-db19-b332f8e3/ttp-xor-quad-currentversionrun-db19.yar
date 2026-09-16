rule TTP_XOR_QUAD_CurrentVersionRun_db19 {
  strings:
    $key_db19 = { 88 76 [2] ac 78 [2] 87 54 [2] a9 76 [2] bd 6d [2] b2 77 [2] ac 6a [2] ae 6b [2] b5 6d [2] a9 6a [2] b5 45 }

  condition:
    any of them
}