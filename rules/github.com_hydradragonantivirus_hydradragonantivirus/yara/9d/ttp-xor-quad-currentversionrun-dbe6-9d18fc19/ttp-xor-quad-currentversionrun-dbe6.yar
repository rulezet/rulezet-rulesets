rule TTP_XOR_QUAD_CurrentVersionRun_dbe6 {
  strings:
    $key_dbe6 = { 88 89 [2] ac 87 [2] 87 ab [2] a9 89 [2] bd 92 [2] b2 88 [2] ac 95 [2] ae 94 [2] b5 92 [2] a9 95 [2] b5 ba }

  condition:
    any of them
}