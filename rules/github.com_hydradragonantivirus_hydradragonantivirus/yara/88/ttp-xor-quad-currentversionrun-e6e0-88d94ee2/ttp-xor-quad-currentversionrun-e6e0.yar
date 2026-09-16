rule TTP_XOR_QUAD_CurrentVersionRun_e6e0 {
  strings:
    $key_e6e0 = { b5 8f [2] 91 81 [2] ba ad [2] 94 8f [2] 80 94 [2] 8f 8e [2] 91 93 [2] 93 92 [2] 88 94 [2] 94 93 [2] 88 bc }

  condition:
    any of them
}