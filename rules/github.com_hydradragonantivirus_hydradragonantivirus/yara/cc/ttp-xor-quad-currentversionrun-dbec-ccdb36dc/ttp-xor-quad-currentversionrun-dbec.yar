rule TTP_XOR_QUAD_CurrentVersionRun_dbec {
  strings:
    $key_dbec = { 88 83 [2] ac 8d [2] 87 a1 [2] a9 83 [2] bd 98 [2] b2 82 [2] ac 9f [2] ae 9e [2] b5 98 [2] a9 9f [2] b5 b0 }

  condition:
    any of them
}