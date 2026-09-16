rule TTP_XOR_QUAD_CurrentVersionRun_feb2 {
  strings:
    $key_feb2 = { ad dd [2] 89 d3 [2] a2 ff [2] 8c dd [2] 98 c6 [2] 97 dc [2] 89 c1 [2] 8b c0 [2] 90 c6 [2] 8c c1 [2] 90 ee }

  condition:
    any of them
}