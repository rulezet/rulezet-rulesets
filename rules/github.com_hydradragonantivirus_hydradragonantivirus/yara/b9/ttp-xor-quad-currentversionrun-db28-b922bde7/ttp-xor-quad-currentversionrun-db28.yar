rule TTP_XOR_QUAD_CurrentVersionRun_db28 {
  strings:
    $key_db28 = { 88 47 [2] ac 49 [2] 87 65 [2] a9 47 [2] bd 5c [2] b2 46 [2] ac 5b [2] ae 5a [2] b5 5c [2] a9 5b [2] b5 74 }

  condition:
    any of them
}