rule TTP_XOR_QUAD_CurrentVersionRun_c83d {
  strings:
    $key_c83d = { 9b 52 [2] bf 5c [2] 94 70 [2] ba 52 [2] ae 49 [2] a1 53 [2] bf 4e [2] bd 4f [2] a6 49 [2] ba 4e [2] a6 61 }

  condition:
    any of them
}