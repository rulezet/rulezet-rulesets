rule TTP_XOR_QUAD_CurrentVersionRun_b0f0 {
  strings:
    $key_b0f0 = { e3 9f [2] c7 91 [2] ec bd [2] c2 9f [2] d6 84 [2] d9 9e [2] c7 83 [2] c5 82 [2] de 84 [2] c2 83 [2] de ac }

  condition:
    any of them
}