rule TTP_XOR_QUAD_CurrentVersionRun_b080 {
  strings:
    $key_b080 = { e3 ef [2] c7 e1 [2] ec cd [2] c2 ef [2] d6 f4 [2] d9 ee [2] c7 f3 [2] c5 f2 [2] de f4 [2] c2 f3 [2] de dc }

  condition:
    any of them
}