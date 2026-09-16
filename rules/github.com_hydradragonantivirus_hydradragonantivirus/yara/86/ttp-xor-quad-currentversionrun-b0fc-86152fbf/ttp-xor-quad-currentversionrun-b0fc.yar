rule TTP_XOR_QUAD_CurrentVersionRun_b0fc {
  strings:
    $key_b0fc = { e3 93 [2] c7 9d [2] ec b1 [2] c2 93 [2] d6 88 [2] d9 92 [2] c7 8f [2] c5 8e [2] de 88 [2] c2 8f [2] de a0 }

  condition:
    any of them
}