rule TTP_XOR_QUAD_CurrentVersionRun_db3d {
  strings:
    $key_db3d = { 88 52 [2] ac 5c [2] 87 70 [2] a9 52 [2] bd 49 [2] b2 53 [2] ac 4e [2] ae 4f [2] b5 49 [2] a9 4e [2] b5 61 }

  condition:
    any of them
}