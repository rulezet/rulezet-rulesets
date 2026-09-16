rule TTP_XOR_QUAD_CurrentVersionRun_db11 {
  strings:
    $key_db11 = { 88 7e [2] ac 70 [2] 87 5c [2] a9 7e [2] bd 65 [2] b2 7f [2] ac 62 [2] ae 63 [2] b5 65 [2] a9 62 [2] b5 4d }

  condition:
    any of them
}