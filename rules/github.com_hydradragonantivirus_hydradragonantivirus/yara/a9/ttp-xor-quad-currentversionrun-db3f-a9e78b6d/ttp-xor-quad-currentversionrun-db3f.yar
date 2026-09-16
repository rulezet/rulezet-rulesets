rule TTP_XOR_QUAD_CurrentVersionRun_db3f {
  strings:
    $key_db3f = { 88 50 [2] ac 5e [2] 87 72 [2] a9 50 [2] bd 4b [2] b2 51 [2] ac 4c [2] ae 4d [2] b5 4b [2] a9 4c [2] b5 63 }

  condition:
    any of them
}