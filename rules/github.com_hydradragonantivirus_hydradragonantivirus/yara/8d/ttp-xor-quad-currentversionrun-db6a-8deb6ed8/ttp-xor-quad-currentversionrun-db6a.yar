rule TTP_XOR_QUAD_CurrentVersionRun_db6a {
  strings:
    $key_db6a = { 88 05 [2] ac 0b [2] 87 27 [2] a9 05 [2] bd 1e [2] b2 04 [2] ac 19 [2] ae 18 [2] b5 1e [2] a9 19 [2] b5 36 }

  condition:
    any of them
}