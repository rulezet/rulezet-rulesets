rule TTP_XOR_QUAD_CurrentVersionRun_e62c {
  strings:
    $key_e62c = { b5 43 [2] 91 4d [2] ba 61 [2] 94 43 [2] 80 58 [2] 8f 42 [2] 91 5f [2] 93 5e [2] 88 58 [2] 94 5f [2] 88 70 }

  condition:
    any of them
}