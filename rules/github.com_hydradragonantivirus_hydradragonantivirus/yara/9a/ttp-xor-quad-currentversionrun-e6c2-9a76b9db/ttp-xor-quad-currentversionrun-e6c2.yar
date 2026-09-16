rule TTP_XOR_QUAD_CurrentVersionRun_e6c2 {
  strings:
    $key_e6c2 = { b5 ad [2] 91 a3 [2] ba 8f [2] 94 ad [2] 80 b6 [2] 8f ac [2] 91 b1 [2] 93 b0 [2] 88 b6 [2] 94 b1 [2] 88 9e }

  condition:
    any of them
}