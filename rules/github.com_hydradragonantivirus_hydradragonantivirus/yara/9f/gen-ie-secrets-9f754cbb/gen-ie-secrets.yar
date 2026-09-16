rule gen_ie_secrets {
  meta:
    author = "@tylabs"

  strings:
    $a = "abe2869f-9b47-4cd9-a358-c22904dba7f7"

  condition:
    all of them
}