rule TTP_XOR_QUAD_CurrentVersionRun_b0fd {
  strings:
    $key_b0fd = { e3 92 [2] c7 9c [2] ec b0 [2] c2 92 [2] d6 89 [2] d9 93 [2] c7 8e [2] c5 8f [2] de 89 [2] c2 8e [2] de a1 }

  condition:
    any of them
}