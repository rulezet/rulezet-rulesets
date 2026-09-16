rule TTP_XOR_QUAD_CurrentVersionRun_db34 {
  strings:
    $key_db34 = { 88 5b [2] ac 55 [2] 87 79 [2] a9 5b [2] bd 40 [2] b2 5a [2] ac 47 [2] ae 46 [2] b5 40 [2] a9 47 [2] b5 68 }

  condition:
    any of them
}