rule TTP_XOR_QUAD_CurrentVersionRun_ba90 {
  strings:
    $key_ba90 = { e9 ff [2] cd f1 [2] e6 dd [2] c8 ff [2] dc e4 [2] d3 fe [2] cd e3 [2] cf e2 [2] d4 e4 [2] c8 e3 [2] d4 cc }

  condition:
    any of them
}