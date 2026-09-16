rule TTP_XOR_QUAD_CurrentVersionRun_d42e {
  strings:
    $key_d42e = { 87 41 [2] a3 4f [2] 88 63 [2] a6 41 [2] b2 5a [2] bd 40 [2] a3 5d [2] a1 5c [2] ba 5a [2] a6 5d [2] ba 72 }

  condition:
    any of them
}