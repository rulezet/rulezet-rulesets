rule TTP_XOR_QUAD_CurrentVersionRun_b00f {
  strings:
    $key_b00f = { e3 60 [2] c7 6e [2] ec 42 [2] c2 60 [2] d6 7b [2] d9 61 [2] c7 7c [2] c5 7d [2] de 7b [2] c2 7c [2] de 53 }

  condition:
    any of them
}