rule TTP_XOR_QUAD_CurrentVersionRun_bfe2 {
  strings:
    $key_bfe2 = { ec 8d [2] c8 83 [2] e3 af [2] cd 8d [2] d9 96 [2] d6 8c [2] c8 91 [2] ca 90 [2] d1 96 [2] cd 91 [2] d1 be }

  condition:
    any of them
}