rule CloudFlareBypass {
  strings:
    $ = "chk_jschl"
    $ = "jschl_vc"
    $ = "jschl_answer"

  condition:
    2 of them  }