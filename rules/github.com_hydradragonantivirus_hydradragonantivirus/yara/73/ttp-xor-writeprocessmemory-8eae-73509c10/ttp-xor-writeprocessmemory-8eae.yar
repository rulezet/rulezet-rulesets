rule TTP_XOR_WriteProcessMemory_8eae {
  strings:
    $key_8eae = { d9 dc [2] eb fe [2] ed cb [2] c3 cb [2] fc d7 }

  condition:
    any of them
}