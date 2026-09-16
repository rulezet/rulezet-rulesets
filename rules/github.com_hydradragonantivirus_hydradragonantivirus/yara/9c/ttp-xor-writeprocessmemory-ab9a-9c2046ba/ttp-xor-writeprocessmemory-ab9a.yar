rule TTP_XOR_WriteProcessMemory_ab9a {
  strings:
    $key_ab9a = { fc e8 [2] ce ca [2] c8 ff [2] e6 ff [2] d9 e3 }

  condition:
    any of them
}