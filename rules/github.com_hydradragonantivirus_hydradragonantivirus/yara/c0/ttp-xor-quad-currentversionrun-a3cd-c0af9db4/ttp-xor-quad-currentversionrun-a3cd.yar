rule TTP_XOR_QUAD_CurrentVersionRun_a3cd {
  strings:
    $key_a3cd = { f0 a2 [2] d4 ac [2] ff 80 [2] d1 a2 [2] c5 b9 [2] ca a3 [2] d4 be [2] d6 bf [2] cd b9 [2] d1 be [2] cd 91 }

  condition:
    any of them
}