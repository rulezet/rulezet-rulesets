rule TTP_XOR_QUAD_CurrentVersionRun_dbe0 {
  strings:
    $key_dbe0 = { 88 8f [2] ac 81 [2] 87 ad [2] a9 8f [2] bd 94 [2] b2 8e [2] ac 93 [2] ae 92 [2] b5 94 [2] a9 93 [2] b5 bc }

  condition:
    any of them
}