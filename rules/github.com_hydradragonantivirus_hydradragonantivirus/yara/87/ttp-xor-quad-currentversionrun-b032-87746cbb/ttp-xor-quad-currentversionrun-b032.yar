rule TTP_XOR_QUAD_CurrentVersionRun_b032 {
  strings:
    $key_b032 = { e3 5d [2] c7 53 [2] ec 7f [2] c2 5d [2] d6 46 [2] d9 5c [2] c7 41 [2] c5 40 [2] de 46 [2] c2 41 [2] de 6e }

  condition:
    any of them
}