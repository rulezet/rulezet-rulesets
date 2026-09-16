rule TTP_XOR_QUAD_CurrentVersionRun_db3c {
  strings:
    $key_db3c = { 88 53 [2] ac 5d [2] 87 71 [2] a9 53 [2] bd 48 [2] b2 52 [2] ac 4f [2] ae 4e [2] b5 48 [2] a9 4f [2] b5 60 }

  condition:
    any of them
}