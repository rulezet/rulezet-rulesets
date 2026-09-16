rule TTP_XOR_QUAD_CurrentVersionRun_b013 {
  strings:
    $key_b013 = { e3 7c [2] c7 72 [2] ec 5e [2] c2 7c [2] d6 67 [2] d9 7d [2] c7 60 [2] c5 61 [2] de 67 [2] c2 60 [2] de 4f }

  condition:
    any of them
}