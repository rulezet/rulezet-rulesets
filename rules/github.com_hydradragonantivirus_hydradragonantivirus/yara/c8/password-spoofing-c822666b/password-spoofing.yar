rule Password_Spoofing {
  strings:
    $a = "with hidden answer"
    $A = "with hidden answer" base64

  condition:
    any of them
}