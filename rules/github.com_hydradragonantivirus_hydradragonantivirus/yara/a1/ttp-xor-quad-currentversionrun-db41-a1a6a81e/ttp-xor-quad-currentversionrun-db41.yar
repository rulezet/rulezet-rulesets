rule TTP_XOR_QUAD_CurrentVersionRun_db41 {
  strings:
    $key_db41 = { 88 2e [2] ac 20 [2] 87 0c [2] a9 2e [2] bd 35 [2] b2 2f [2] ac 32 [2] ae 33 [2] b5 35 [2] a9 32 [2] b5 1d }

  condition:
    any of them
}