rule TTP_XOR_QUAD_CurrentVersionRun_db0a {
  strings:
    $key_db0a = { 88 65 [2] ac 6b [2] 87 47 [2] a9 65 [2] bd 7e [2] b2 64 [2] ac 79 [2] ae 78 [2] b5 7e [2] a9 79 [2] b5 56 }

  condition:
    any of them
}