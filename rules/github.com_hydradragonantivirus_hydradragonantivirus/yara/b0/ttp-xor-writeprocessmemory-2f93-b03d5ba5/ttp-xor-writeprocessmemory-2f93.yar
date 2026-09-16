rule TTP_XOR_WriteProcessMemory_2f93 {
  strings:
    $key_2f93 = { 78 e1 [2] 4a c3 [2] 4c f6 [2] 62 f6 [2] 5d ea }

  condition:
    any of them
}