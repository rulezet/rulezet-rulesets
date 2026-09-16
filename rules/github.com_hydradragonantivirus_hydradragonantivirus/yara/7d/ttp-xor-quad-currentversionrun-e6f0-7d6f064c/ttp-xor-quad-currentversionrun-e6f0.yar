rule TTP_XOR_QUAD_CurrentVersionRun_e6f0 {
  strings:
    $key_e6f0 = { b5 9f [2] 91 91 [2] ba bd [2] 94 9f [2] 80 84 [2] 8f 9e [2] 91 83 [2] 93 82 [2] 88 84 [2] 94 83 [2] 88 ac }

  condition:
    any of them
}