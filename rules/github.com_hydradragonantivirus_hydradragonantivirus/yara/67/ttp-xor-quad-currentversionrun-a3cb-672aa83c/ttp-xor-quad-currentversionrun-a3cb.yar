rule TTP_XOR_QUAD_CurrentVersionRun_a3cb {
  strings:
    $key_a3cb = { f0 a4 [2] d4 aa [2] ff 86 [2] d1 a4 [2] c5 bf [2] ca a5 [2] d4 b8 [2] d6 b9 [2] cd bf [2] d1 b8 [2] cd 97 }

  condition:
    any of them
}