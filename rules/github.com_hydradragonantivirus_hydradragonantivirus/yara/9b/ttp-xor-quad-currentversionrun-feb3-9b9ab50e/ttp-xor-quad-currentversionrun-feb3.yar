rule TTP_XOR_QUAD_CurrentVersionRun_feb3 {
  strings:
    $key_feb3 = { ad dc [2] 89 d2 [2] a2 fe [2] 8c dc [2] 98 c7 [2] 97 dd [2] 89 c0 [2] 8b c1 [2] 90 c7 [2] 8c c0 [2] 90 ef }

  condition:
    any of them
}